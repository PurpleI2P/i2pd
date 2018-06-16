#ifndef STORAGE_H
#define STORAGE_H
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#ifdef LMDB
#include <lmdb.h>
#endif

#include "FS.h"
#include "Identity.h"
#include "Log.h"

namespace i2p
{
namespace data
{

class StorageRecord
{
public:
	std::shared_ptr<char[]> data;
	size_t len;
	StorageRecord(size_t len): data(new char[len]), len(len) {}
	StorageRecord(const char *buf, size_t len): StorageRecord(len)
	{
		memcpy(data.get(), buf, len);
	}

	StorageRecord():  data(nullptr), len(0) {}
	bool IsValid() { return len > 0; }
};

typedef std::function<void(const IdentHash&, const StorageRecord&)> DVisitor;

class IdentStorage
{
public:
	IdentStorage() {}
	virtual bool Init();
	virtual void DeInit() {}
	virtual bool BeginUpdate() { return true; }
	virtual bool EndUpdate() { return true; }
	virtual bool Store(const IdentHash &, const StorageRecord&) { return true; }
	virtual bool Remove(const IdentHash &) { return true; }
	virtual StorageRecord Fetch(const IdentHash&) { return StorageRecord(); }
	virtual void Iterate(const DVisitor&) {}
	virtual ~IdentStorage();
};

class FsIdentStorage : public IdentStorage
{
public:
	FsIdentStorage(const char *name, const char* dprefix, const char *fprefix, const char *suffix, bool isB32=false) :
		m_Storage(name, dprefix, fprefix, suffix), m_Fprefix(fprefix), m_IsB32(isB32) {}

	virtual bool Init();
	virtual void DeInit() {}
	virtual bool BeginUpdate() { return true; }
	virtual bool EndUpdate() { return true; }
	virtual bool Store(const IdentHash &, const StorageRecord&);
	virtual bool Remove(const IdentHash &);
	StorageRecord Fetch(const IdentHash&);
	virtual void Iterate(const DVisitor&);
	virtual ~FsIdentStorage();

private:
	i2p::fs::HashedStorage m_Storage;
	std::string m_Fprefix;
	bool m_IsB32;
};

#ifdef LMDB
class MdbIdentStorage : public IdentStorage
{
public:
	MdbIdentStorage(const char *name) : m_Name(name) {}
	virtual bool Init();
	virtual void DeInit();
	virtual bool BeginUpdate();
	virtual bool EndUpdate();
	virtual bool Store(const IdentHash &, const StorageRecord&);
	virtual bool Remove(const IdentHash &);
	StorageRecord Fetch(const IdentHash&);
	virtual void Iterate(const DVisitor&);
	virtual ~MdbIdentStorage();
private:
	bool InitRead();
	void DeInitRead();
	bool InitWrite();

	bool DeInitWrite();
	bool m_Initialized = false;
	std::string m_Path;
	std::string m_Name;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_txn *txn;
};
#endif
} //ns data
} //ns i2p

#endif // STORAGE_H
