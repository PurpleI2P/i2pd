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

} //ns data
} //ns i2p
