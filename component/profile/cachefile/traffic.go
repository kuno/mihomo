package cachefile

import (
	"encoding/binary"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

var (
	keyUploadTotal   = []byte("upload_total")
	keyDownloadTotal = []byte("download_total")
)

func (c *CacheFile) SetTrafficTotals(uploadTotal, downloadTotal int64) {
	if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketTraffic)
		if err != nil {
			return err
		}

		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(uploadTotal))
		if err = bucket.Put(keyUploadTotal, buf[:]); err != nil {
			return err
		}

		binary.BigEndian.PutUint64(buf[:], uint64(downloadTotal))
		return bucket.Put(keyDownloadTotal, buf[:])
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *CacheFile) GetTrafficTotals() (uploadTotal, downloadTotal int64) {
	if c.DB == nil {
		return
	}

	c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketTraffic)
		if bucket == nil {
			return nil
		}

		if v := bucket.Get(keyUploadTotal); len(v) == 8 {
			uploadTotal = int64(binary.BigEndian.Uint64(v))
		}
		if v := bucket.Get(keyDownloadTotal); len(v) == 8 {
			downloadTotal = int64(binary.BigEndian.Uint64(v))
		}
		return nil
	})

	return
}
