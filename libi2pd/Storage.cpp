#include <iostream>
#include <ios>

#include <boost/filesystem.hpp>

#include "Storage.h"

namespace i2p {
namespace data {

FsIdentStorage::~FsIdentStorage() {}
IdentStorage::~IdentStorage() {}

bool IdentStorage::Init() { return true; }
bool FsIdentStorage::Init()
{
	m_Storage.SetPlace(i2p::fs::GetDataDir());
	if (m_IsB32)
		m_Storage.Init(i2p::data::GetBase32SubstitutionTable(), 32);
	else
		m_Storage.Init(i2p::data::GetBase64SubstitutionTable(), 64);
	return true;
}

bool FsIdentStorage::Store(const i2p::data::IdentHash &ident, const StorageRecord &record)
{
	std::string strid = m_IsB32 ? ident.ToBase32() : ident.ToBase64();
	std::string path = m_Storage.Path(strid);
	std::ofstream ofs(path, std::ios::binary);
	ofs.write(record.data.get(), record.len);
	ofs.flush();
	return true;
}

StorageRecord FsIdentStorage::Fetch(const i2p::data::IdentHash &ident)
{
	std::string strid = m_IsB32 ? ident.ToBase32() : ident.ToBase64();
	std::string path = m_Storage.Path(strid);
	if (boost::filesystem::exists(path)) {
		std::ifstream ifs(path, std::ios::binary);
		ifs.seekg(0, std::ios::end);

		int size = ifs.tellg();
		ifs.seekg(0, std::ios::beg);

		StorageRecord result(size);

		ifs.read(result.data.get(), size);
		return result;
	}

	return StorageRecord();
}

bool FsIdentStorage::Remove(const IdentHash & ident)
{
	std::string strid = m_IsB32 ? ident.ToBase32() : ident.ToBase64();
	std::string path = m_Storage.Path(strid);
	return i2p::fs::Remove(path);
}

void FsIdentStorage::Iterate(const DVisitor &f)
{
	auto fv = [&f, this](const std::string &path)
	{
		boost::filesystem::path p(path);
		std::string id = p.stem().string().substr(m_Fprefix.length());
		i2p::data::IdentHash ident;
		if (m_IsB32)
			ident.FromBase32(id);
		else
			ident.FromBase64(id);
		StorageRecord data = Fetch(ident);
		if (data.IsValid()) f(ident,data);
	};

	m_Storage.Iterate(fv);
}

#ifdef LMDB
//MdbIdentStorage
MdbIdentStorage::~MdbIdentStorage()
{
}

bool MdbIdentStorage::Init()
{
	m_Path = i2p::fs::GetDataDir() + i2p::fs::dirSep + m_Name;

	if (!boost::filesystem::exists(m_Path))
		boost::filesystem::create_directory(m_Path);

	if (!mdb_env_create(&env))
	{

		int ret = mdb_env_open(env, m_Path.c_str(), MDB_NOTLS, 0664);
		if (!ret)
		{
			return true;
		}
		mdb_env_close(env);
	}
	return false;
}

void MdbIdentStorage::DeInit()
{
	if (m_Initialized)
		DeInitWrite();
	mdb_env_close(env);
}

bool MdbIdentStorage::BeginUpdate()  //TODO: remove unneeded memory juggling
{
	return InitWrite();
}

bool MdbIdentStorage::EndUpdate()
{
	return DeInitWrite();
}

bool MdbIdentStorage::Store(const i2p::data::IdentHash &ident, const StorageRecord& record)
{
	if (!m_Initialized)
	{
		return false;
	}

	MDB_val data;
	data.mv_data = const_cast<char*>(record.data.get());
	data.mv_size = record.len;

	MDB_val key;
	key.mv_data = const_cast<uint8_t*>(ident.data());
	key.mv_size = 32;
	return !mdb_put(txn, dbi, &key, &data, 0);
}

StorageRecord MdbIdentStorage::Fetch(const i2p::data::IdentHash &ident)
{
	StorageRecord result;

	MDB_txn *trn;
	MDB_dbi dbh;
	if (!mdb_txn_begin(env, NULL, MDB_RDONLY, &trn))
	{
		if (!mdb_open(trn, NULL, 0, &dbh))
		{
			MDB_val key, data;
			key.mv_data = const_cast<uint8_t*>(ident.data());
			key.mv_size = 32;
			if (!mdb_get(trn, dbh, &key, &data))
			{
				result = StorageRecord((char*)data.mv_data, data.mv_size);
			}

			mdb_txn_abort(trn);
			mdb_close(env, dbh);
		}
	}
	return result;
}

bool MdbIdentStorage::Remove(const IdentHash &ident)
{
	if (!m_Initialized)
	{
		return false;
	}

	MDB_val key;
	key.mv_data = const_cast<uint8_t*>(ident.data());
	key.mv_size = 32;
	return !mdb_del(txn, dbi, &key, NULL);
}

void MdbIdentStorage::Iterate(const DVisitor & f)
{
	MDB_txn *trn;
	MDB_dbi dbh;
	MDB_val data, key;
	MDB_cursor *cursor;

	if(!mdb_txn_begin(env, NULL, MDB_RDONLY, &trn))
	{
		if (!mdb_open(trn, NULL, 0, &dbh))
		{
			if (!mdb_cursor_open(trn, dbh, &cursor))
			{
				while(!mdb_cursor_get(cursor, &key, &data, MDB_NEXT))
				{
					StorageRecord record((char*)data.mv_data, data.mv_size);
					IdentHash ident((uint8_t*)key.mv_data);
					f(ident, record);
				}
				mdb_cursor_close(cursor);
			}

			mdb_txn_abort(trn);
			mdb_close(env, dbh);
		} else
		{
			mdb_txn_abort(trn);
		}
	}
}

bool MdbIdentStorage::InitWrite()
{
	int ret = mdb_txn_begin(env, NULL, 0, &txn);
	if (ret)
		return false;

	ret = mdb_open(txn, NULL, 0, &dbi);
	if (ret)
	{
		mdb_txn_abort(txn);
		return false;
	}
	m_Initialized = true;
	return true;
}

bool MdbIdentStorage::DeInitWrite() {
	int ret = mdb_txn_commit(txn);
	mdb_close(env, dbi);
	m_Initialized = false;
	return  !ret;
}
#endif

} //ns data
} //ns i2p
