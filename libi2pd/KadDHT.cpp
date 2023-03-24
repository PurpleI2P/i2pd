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
		zero (nullptr), one (nullptr)
	{
	}
	
	DHTNode::~DHTNode ()
	{
		if (zero) delete zero;
		if (one) delete one;
	}	

	void DHTNode::MoveRouterUp (bool fromOne)
	{
		DHTNode *& side = fromOne ? one : zero;
		if (side)
		{
			if (router) router = nullptr; // shouldn't happen
			router = side->router;
			side->router = nullptr;
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

	void DHTTable::Clear ()
	{
		m_Size = 0;
		delete m_Root;
		m_Root = new DHTNode;
	}	
		
	void DHTTable::Insert (const std::shared_ptr<RouterInfo>& r)
	{
		if (!r) return;
		return Insert (r, m_Root, 0);
	}	

	void DHTTable::Insert (const std::shared_ptr<RouterInfo>& r, DHTNode * root, int level)
	{
		if (root->router)
		{	
			if (root->router->GetIdentHash () == r->GetIdentHash ()) 
			{
				root->router = r; // replace
				return;
			}	
			auto r2 = root->router;
			root->router = nullptr; m_Size--;
			int bit1, bit2;
			do
			{	
				bit1 = r->GetIdentHash ().GetBit (level);
				bit2 = r2->GetIdentHash ().GetBit (level);
				if (bit1 == bit2)
				{	
					if (bit1)
					{
						if (root->one) return; // something wrong
						root->one = new DHTNode;
						root = root->one;
					}	
					else
					{
						if (root->zero) return; // something wrong
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
				Insert (r2, root->zero, level + 1);
				Insert (r, root->one, level + 1);
			}
			else
			{
				Insert (r2, root->one, level + 1);
				Insert (r, root->zero, level + 1);
			}	
		}
		else
		{
			if (!root->zero && !root->one)
			{
				root->router = r; m_Size++;
				return;
			}
			int bit = r->GetIdentHash ().GetBit (level);
			if (bit)
			{
				if (!root->one)
					root->one = new DHTNode;
				Insert (r, root->one, level + 1);
			}	
			else
			{
				if (!root->zero)
					root->zero = new DHTNode;
				Insert (r, root->zero, level + 1);
			}	
		}	
	}	

	bool DHTTable::Remove (const IdentHash& h)
	{
		return Remove (h, m_Root, 0);
	}	
		
	bool DHTTable::Remove (const IdentHash& h, DHTNode * root, int level)
	{
		if (root)
		{
			if (root->router && root->router->GetIdentHash () == h)
			{
				root->router = nullptr;
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
						if (root->zero && root->zero->router)
							root->MoveRouterUp (false);
					}	
					else if (root->one->router && !root->zero)
						root->MoveRouterUp (true);
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
						if (root->one && root->one->router)
							root->MoveRouterUp (true);
					}	
					else if (root->zero->router && !root->one)
						root->MoveRouterUp (false);
					return true;
				}
			}	
		}	
		return false;
	}	

	std::shared_ptr<RouterInfo> DHTTable::FindClosest (const IdentHash& h, const Filter& filter) const
	{
		if (filter) m_Filter = filter;
		auto r = FindClosest (h, m_Root, 0);
		m_Filter = nullptr;
		return r;
	}	

	std::shared_ptr<RouterInfo> DHTTable::FindClosest (const IdentHash& h, DHTNode * root, int level) const
	{
		bool split = false;
		do 
		{	
			if (root->router) 
				return (!m_Filter || m_Filter (root->router)) ? root->router : nullptr;	
			split = root->zero && root->one;
			if (!split)
			{
				if (root->zero) root = root->zero;
				else if (root->one) root = root->one;
				else return nullptr;
				level++;	
			}		
		}
		while (!split);
		int bit = h.GetBit (level);
		if (bit)
		{
			if (root->one)
			{	
				auto r = FindClosest (h, root->one, level + 1);
				if (r) return r;
			}	
			if (root->zero)
			{
				auto r = FindClosest (h, root->zero, level + 1);
				if (r) return r;
			}	
		}	
		else
		{
			if (root->zero)
			{	
				auto r = FindClosest (h, root->zero, level + 1);
				if (r) return r;
			}	
			if (root->one)
			{	
				auto r = FindClosest (h, root->one, level + 1);
				if (r) return r;
			}	
		}
		return nullptr;
	}	

	std::vector<std::shared_ptr<RouterInfo> > DHTTable::FindClosest (const IdentHash& h, size_t num, const Filter& filter) const
	{
		std::vector<std::shared_ptr<RouterInfo> > vec;
		if (num > 0)
		{
			if (filter) m_Filter = filter;
			FindClosest (h, num, m_Root, 0, vec);
			m_Filter = nullptr;
		}	
		return vec;
	}	

	void DHTTable::FindClosest (const IdentHash& h, size_t num, DHTNode * root, int level, std::vector<std::shared_ptr<RouterInfo> >& hashes) const
	{
		if (hashes.size () >= num) return;
		bool split = false;
		do 
		{	
			if (root->router)
			{	
				if (!m_Filter || m_Filter (root->router)) 
					hashes.push_back (root->router);
				return;
			}	
			split = root->zero && root->one;
			if (!split)
			{
				if (root->zero) root = root->zero;
				else if (root->one) root = root->one;
				else return;
				level++;	
			}		
		}
		while (!split);
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

	void DHTTable::Cleanup (const Filter& filter)
	{
		if (filter)
		{	
			m_Filter = filter;
			Cleanup (m_Root);
			m_Filter = nullptr;
		}	
		else
			Clear ();
	}	

	void DHTTable::Cleanup (DHTNode * root)
	{
		if (!root) return;
		if (root->router)
		{
			if (!m_Filter || !m_Filter (root->router))
			{	
				m_Size--;
				root->router = nullptr;	
			}	
			return;
		}	
		if (root->zero) 
		{	
			Cleanup (root->zero);
			if (root->zero->IsEmpty ()) 
			{
				delete root->zero;
				root->zero = nullptr;
			}
		}	
		if (root->one) 
		{	
			Cleanup (root->one);
			if (root->one->IsEmpty ()) 
			{
				delete root->one;
				root->one = nullptr;
				if (root->zero && root->zero->router)
					root->MoveRouterUp (false);
			}
			else if (root->one->router && !root->zero)
				root->MoveRouterUp (true);
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
		if (root->router)
		{
			if (!root->zero && !root->one)
				s << '>' << GetIdentHashAbbreviation (root->router->GetIdentHash ());
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
