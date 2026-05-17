package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zafrem/bastion-sentinel/types"
)

const keyPrefix = "sentinel:v1:"

type redisCache struct {
	client *redis.Client
}

func newRedisCache(addr string) (*redisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})
	// verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &redisCache{client: client}, nil
}

func (c *redisCache) Get(key string) (types.ValidateResponse, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	data, err := c.client.Get(ctx, keyPrefix+key).Bytes()
	if err != nil {
		return types.ValidateResponse{}, false
	}
	var resp types.ValidateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return types.ValidateResponse{}, false
	}
	return resp, true
}

func (c *redisCache) Set(key string, resp types.ValidateResponse, ttl time.Duration) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = c.client.Set(ctx, keyPrefix+key, data, ttl).Err()
}

func (c *redisCache) Flush() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// delete only our keys to avoid wiping unrelated data
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, keyPrefix+"*", 100).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			_ = c.client.Del(ctx, keys...).Err()
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (c *redisCache) Close() error {
	return c.client.Close()
}
