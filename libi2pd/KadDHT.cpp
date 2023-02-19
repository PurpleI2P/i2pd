/*
* Copyright (c) 2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
*/

#include "KadDHT.h"

namespace i2p 
{
namespace data 
{
	DHTNode::DHTNode ():
		zero (nullptr), one (nullptr), hash (nullptr)
	{
	}
	
	DHTNode::~DHTNode ()
	{
		if (zero) delete zero;
		if (one) delete one;
		if (hash) delete hash;
	}	

	void DHTNode::MoveHashUp (bool fromOne)
	{
		DHTNode *& side = fromOne ? one : zero;
		if (side)
		{
			if (hash) delete hash; // shouldn't happen
			hash = side->hash;
			side->hash = nullptr;
			delete side;
			side = nullptr;
		}	
	}	
		
	DHTTable::DHTTable (): 
		m_Size (0)
	{
		m_Root = new DHTNode;
	}
		
	DHTTable::~DHTTable ()
	{
		delete m_Root;
	}	

	DHTNode * DHTTable::Insert (const IdentHash& h)
	{
		return Insert (new IdentHash (h), m_Root, 0);
	}	

	DHTNode * DHTTable::Insert (IdentHash * h, DHTNode * root, int level)
	{
		if (root->hash)
		{	
			if (*(root->hash) == *h) 
			{
				delete h;
				return root;
			}	
			auto h2 = root->hash;
			root->hash = nullptr; m_Size--;
			int bit1, bit2;
			do
			{	
				bit1 = h->GetBit (level);
				bit2 = h2->GetBit (level);
				if (bit1 == bit2)
				{	
					if (bit1)
					{
						if (root->one) return nullptr; // someting wrong
						root->one = new DHTNode;
						root = root->one;
					}	
					else
					{
						if (root->zero) return nullptr; // someting wrong
						root->zero = new DHTNode;
						root = root->zero;
					}	
					level++;
				}	
			}
			while (bit1 == bit2);
			
			if (!root->zero)
				root->zero = new DHTNode;
			if (!root->one)
				root->one = new DHTNode;
			if (bit1)
			{
				Insert (h2, root->zero, level + 1);
				return Insert (h, root->one, level + 1);
			}
			else
			{
				Insert (h2, root->one, level + 1);
				return Insert (h, root->zero, level + 1);
			}	
		}
		else
		{
			if (!root->zero && !root->one)
			{
				root->hash = h; m_Size++;
				return root;
			}
			int bit = h->GetBit (level);
			if (bit)
			{
				if (!root->one)
					root->one = new DHTNode;
				return Insert (h, root->one, level + 1);
			}	
			else
			{
				if (!root->zero)
					root->zero = new DHTNode;
				return Insert (h, root->zero, level + 1);
			}	
		}	
		return nullptr;
	}	

	bool DHTTable::Remove (const IdentHash& h)
	{
		return Remove (h, m_Root, 0);
	}	
		
	bool DHTTable::Remove (const IdentHash& h, DHTNode * root, int level)
	{
		if (root)
		{
			if (root->hash && *(root->hash) == h)
			{
				delete root->hash; root->hash = nullptr;
				m_Size--;
				return true;
			}	
			int bit = h.GetBit (level);
			if (bit)
			{
				if (root->one && Remove (h, root->one, level + 1))
				{    
					if (root->one->IsEmpty ())
					{
						delete root->one;
						root->one = nullptr;
						if (root->zero && root->zero->hash)
							root->MoveHashUp (false);
					}	
					else if (root->one->hash && !root->zero)
						root->MoveHashUp (true);
					return true;
				}	
			}
			else
			{
				if (root->zero && Remove (h, root->zero, level + 1))
				{    
					if (root->zero->IsEmpty ())
					{
						delete root->zero;
						root->zero = nullptr;
						if (root->one && root->one->hash)
							root->MoveHashUp (true);
					}	
					else if (root->zero->hash && !root->one)
						root->MoveHashUp (false);
					return true;
				}
			}	
		}	
		return false;
	}	

	IdentHash * DHTTable::FindClosest (const IdentHash& h)
	{
		return FindClosest (h, m_Root, 0);
	}	

	IdentHash * DHTTable::FindClosest (const IdentHash& h, DHTNode * root, int level)
	{
		if (root->hash) return root->hash;
		int bit = h.GetBit (level);
		if (bit)
		{
			if (root->one)
				return FindClosest (h, root->one, level + 1);
			if (root->zero)
				return FindClosest (h, root->zero, level + 1);
		}	
		else
		{
			if (root->zero)
				return FindClosest (h, root->zero, level + 1);
			if (root->one)
				return FindClosest (h, root->one, level + 1);
		}
		return nullptr;
	}	

	std::vector<IdentHash *> DHTTable::FindClosest (const IdentHash& h, size_t num)
	{
		std::vector<IdentHash *> vec;
		if (num > 0)
			FindClosest (h, num, m_Root, 0, vec);
		return vec;
	}	

	void DHTTable::FindClosest (const IdentHash& h, size_t num, DHTNode * root, int level, std::vector<IdentHash *>& hashes)
	{
		if (hashes.size () >= num) return;
		if (root->hash)
		{	
			hashes.push_back (root->hash);
			return;
		}	
		int bit = h.GetBit (level);
		if (bit)
		{
			if (root->one)
				FindClosest (h, num, root->one, level + 1, hashes);
			if (hashes.size () < num && root->zero)
				FindClosest (h, num, root->zero, level + 1, hashes);
		}
		else
		{
			if (root->zero)
				FindClosest (h, num, root->zero, level + 1, hashes);
			if (hashes.size () < num && root->one)
				FindClosest (h, num, root->one, level + 1, hashes);
		}	
	}	
		
	void DHTTable::Print (std::stringstream& s)
	{
		Print (s, m_Root, 0);
	}	

	void DHTTable::Print (std::stringstream& s, DHTNode * root, int level)
	{
		if (!root) return;
		s << std::string (level, '-');
		if (root->hash)
		{
			if (!root->zero && !root->one)
				s << '>' << GetIdentHashAbbreviation (*(root->hash));
			else	
				s << "error";
		}	
		s << std::endl;
		if (root->zero)
		{
			s << std::string (level, '-') << "0" << std::endl;
			Print (s, root->zero, level + 1);
		}	
		if (root->one)
		{
			s << std::string (level, '-') << "1" << std::endl;
			Print (s, root->one, level + 1);
		}	
	}	
}
}
