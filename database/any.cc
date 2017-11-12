#include"any.h"
using namespace std;

Any::operator std::string() 
{
	//if(t == INT) return u.n;//throw AnyException();
	return str;
}

Any::operator int()
{
	if(t != INT) throw AnyException();
	else return u.n;
}

Any::operator float()
{
	if(t != FLOAT) throw AnyException();
	else return u.f;
}

ostream& operator<<(ostream& o, Any rhs)//const ....?
{
	o << (string)rhs;
	return o;
}


bool Any::operator==(const Any& r) const
{
	switch(t) {
		case STRING: return str == r.str;
		case INT: return u.n == r.u.n;
		case FLOAT: return u.f == r.u.f;
	}
}

bool Any::operator!=(const Any& r) const
{
	return !(*this == r);
}

bool Any::operator<(const Any& r) const
{
	switch(t) {
		case STRING: return str < r.str;
		case INT: return u.n < r.u.n;
		case FLOAT: return u.f < r.u.f;
	}
}
		
Any::Any(string s)
{
	str = s;
	t = STRING;
}

Any::Any(int n)
{
	u.n = n;
	t = INT;
	str = to_string(n);
}

Any::Any(float f)
{
	u.f = f;
	t = FLOAT;
	str = to_string(f);
}

Any& Any::operator=(int n)
{
	u.n = n;
	t = INT;
	str = to_string(n);
}

Any& Any::operator=(float f)
{
	u.f = f;
	t = FLOAT;
	str = to_string(f);
}

Any& Any::operator=(string s)
{
	str = s;
	t = STRING;
}

