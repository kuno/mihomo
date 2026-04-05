package cachefile

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/profile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

var (
	initOnce     sync.Once
	cacheMux     sync.Mutex
	fileMode     os.FileMode = 0o666
	defaultCache *CacheFile

	bucketSelected         = []byte("selected")
	bucketFakeip           = []byte("fakeip")
	bucketFakeip6          = []byte("fakeip6")
	bucketETag             = []byte("etag")
	bucketSubscriptionInfo = []byte("subscriptioninfo")
	bucketStorage          = []byte("storage")
	bucketTraffic          = []byte("traffic")
)

// CacheFile store and update the cache file
type CacheFile struct {
	DB   *bbolt.DB
	path string
}

func (c *CacheFile) SetSelected(group, selected string) {
	if !profile.StoreSelected.Load() {
		return
	} else if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSelected)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), []byte(selected))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}

func (c *CacheFile) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	} else if c.DB == nil {
		return nil
	}

	mapping := map[string]string{}
	c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketSelected)
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			mapping[string(k)] = string(v)
		}
		return nil
	})
	return mapping
}

func (c *CacheFile) Close() error {
	if c == nil || c.DB == nil {
		return nil
	}
	return c.DB.Close()
}

func initCache() {
	defaultCache = &CacheFile{}
	defaultCache.ensureOpen()
}

func (c *CacheFile) ensureOpen() {
	cacheMux.Lock()
	defer cacheMux.Unlock()

	cachePath := C.Path.Cache()
	if c.DB != nil && c.path == cachePath {
		return
	}
	if c.DB != nil {
		if err := c.DB.Close(); err != nil {
			log.Warnln("[CacheFile] close cache file %s failed: %s", c.path, err.Error())
		}
		c.DB = nil
	}

	db, _ := openCache(cachePath)
	c.DB = db
	c.path = cachePath
}

func openCache(cachePath string) (*bbolt.DB, error) {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o777); err != nil {
		return nil, err
	}

	options := bbolt.Options{Timeout: time.Second, NoStatistics: true}
	db, err := bbolt.Open(cachePath, fileMode, &options)
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(cachePath); err != nil {
			log.Debugln("[CacheFile] remove invalid cache file error: %s", err.Error())
			break
		}
		log.Debugln("[CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(cachePath, fileMode, &options)
	}
	return db, err
}

// Cache return singleton of CacheFile
func Cache() *CacheFile {
	initOnce.Do(initCache)
	defaultCache.ensureOpen()

	return defaultCache
}
