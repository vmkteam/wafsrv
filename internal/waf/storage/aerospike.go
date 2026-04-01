package storage

import (
	"errors"
	"fmt"
	"time"

	as "github.com/aerospike/aerospike-client-go/v7"
)

// AerospikeConfig holds Aerospike connection settings.
type AerospikeConfig struct {
	Hosts          []string      // ["127.0.0.1:3000"]
	Namespace      string        // "wafsrv"
	KeyPrefix      string        // optional key prefix for multi-tenant isolation (e.g. "apisrv:")
	ConnectTimeout time.Duration // 5s
	OperTimeout    time.Duration // 50ms per-operation
}

// Aerospike provides both Counter and KVStore backed by Aerospike.
type Aerospike struct {
	client    *as.Client
	namespace string
	keyPrefix string
	readPol   *as.BasePolicy
	writePol  *as.WritePolicy
}

// NewAerospike creates an Aerospike client and returns a shared store.
func NewAerospike(cfg AerospikeConfig) (*Aerospike, error) {
	if len(cfg.Hosts) == 0 {
		return nil, errors.New("storage: no aerospike hosts configured")
	}

	hosts, err := as.NewHosts(cfg.Hosts...)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid aerospike hosts: %w", err)
	}

	policy := as.NewClientPolicy()
	policy.Timeout = cfg.ConnectTimeout
	policy.ConnectionQueueSize = 256

	client, err := as.NewClientWithPolicyAndHost(policy, hosts...)
	if err != nil {
		return nil, fmt.Errorf("storage: aerospike connect: %w", err)
	}

	readPol := as.NewPolicy()
	readPol.SocketTimeout = cfg.OperTimeout
	readPol.TotalTimeout = cfg.OperTimeout

	writePol := as.NewWritePolicy(0, 0)
	writePol.SocketTimeout = cfg.OperTimeout
	writePol.TotalTimeout = cfg.OperTimeout

	return &Aerospike{
		client:    client,
		namespace: cfg.Namespace,
		keyPrefix: cfg.KeyPrefix,
		readPol:   readPol,
		writePol:  writePol,
	}, nil
}

// prefixKey prepends the configured key prefix (if any) for multi-tenant isolation.
func (a *Aerospike) prefixKey(key string) string {
	if a.keyPrefix == "" {
		return key
	}

	return a.keyPrefix + key
}

// Close closes the Aerospike client connection.
func (a *Aerospike) Close() {
	a.client.Close()
}

// Counter returns an AerospikeCounter using this connection.
func (a *Aerospike) Counter(set string) *AerospikeCounter {
	return &AerospikeCounter{a: a, set: set}
}

// KV returns an AerospikeKV using this connection.
func (a *Aerospike) KV(set string) *AerospikeKV {
	return &AerospikeKV{a: a, set: set}
}

// --- Counter ---

// AerospikeCounter implements Counter using Aerospike atomic Operate.
type AerospikeCounter struct {
	a   *Aerospike
	set string
}

func (c *AerospikeCounter) Allow(key string, limit int, window time.Duration) (bool, error) {
	count, err := c.a.atomicIncrement(c.set, key, window)
	if err != nil {
		return true, err // fail-open
	}

	return int(count) <= limit, nil
}

// --- KVStore ---

// AerospikeKV implements KVStore using Aerospike.
type AerospikeKV struct {
	a   *Aerospike
	set string
}

func (kv *AerospikeKV) Get(key string) ([]byte, bool, error) {
	asKey, err := as.NewKey(kv.a.namespace, kv.set, kv.a.prefixKey(key))
	if err != nil {
		return nil, false, fmt.Errorf("storage: aerospike key: %w", err)
	}

	rec, err := kv.a.client.Get(kv.a.readPol, asKey, "v")
	if err != nil {
		if err.Matches(as.ErrKeyNotFound.ResultCode) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("storage: aerospike get: %w", err)
	}

	if rec == nil {
		return nil, false, nil
	}

	val, ok := rec.Bins["v"].([]byte)
	if !ok {
		return nil, false, nil
	}

	return val, true, nil
}

func (kv *AerospikeKV) Set(key string, value []byte, ttl time.Duration) error {
	asKey, err := as.NewKey(kv.a.namespace, kv.set, kv.a.prefixKey(key))
	if err != nil {
		return fmt.Errorf("storage: aerospike key: %w", err)
	}

	wp := *kv.a.writePol
	if ttl > 0 {
		wp.Expiration = uint32(ttl.Seconds())
	}

	return kv.a.client.Put(&wp, asKey, as.BinMap{"v": value})
}

func (kv *AerospikeKV) Delete(key string) error {
	asKey, err := as.NewKey(kv.a.namespace, kv.set, kv.a.prefixKey(key))
	if err != nil {
		return fmt.Errorf("storage: aerospike key: %w", err)
	}

	wp := *kv.a.writePol

	_, err = kv.a.client.Delete(&wp, asKey)
	if err != nil && !err.Matches(as.ErrKeyNotFound.ResultCode) {
		return fmt.Errorf("storage: aerospike delete: %w", err)
	}

	return nil
}

func (kv *AerospikeKV) Exists(key string) (bool, error) {
	asKey, err := as.NewKey(kv.a.namespace, kv.set, kv.a.prefixKey(key))
	if err != nil {
		return false, fmt.Errorf("storage: aerospike key: %w", err)
	}

	exists, err := kv.a.client.Exists(kv.a.readPol, asKey)
	if err != nil {
		return false, fmt.Errorf("storage: aerospike exists: %w", err)
	}

	return exists, nil
}

func (kv *AerospikeKV) Increment(key string, ttl time.Duration) (int64, error) {
	return kv.a.atomicIncrement(kv.set, key, ttl)
}

// atomicIncrement atomically adds 1 to a counter bin and returns the new value.
func (a *Aerospike) atomicIncrement(set, key string, ttl time.Duration) (int64, error) {
	asKey, err := as.NewKey(a.namespace, set, a.prefixKey(key))
	if err != nil {
		return 0, fmt.Errorf("storage: aerospike key: %w", err)
	}

	wp := *a.writePol
	if ttl > 0 {
		wp.Expiration = uint32(ttl.Seconds())
	}

	rec, err := a.client.Operate(&wp, asKey,
		as.AddOp(as.NewBin("c", 1)),
		as.GetOp(),
	)
	if err != nil {
		return 0, fmt.Errorf("storage: aerospike operate: %w", err)
	}

	count, _ := rec.Bins["c"].(int)

	return int64(count), nil
}
