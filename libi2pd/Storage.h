#ifndef STORAGE_H
#define STORAGE_H
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

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

} //ns data
} //ns i2p

#endif // STORAGE_H
