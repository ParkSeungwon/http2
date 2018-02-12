#include<sstream>
#include<istream>
#include"ber.h"
#include"crypt.h"
using namespace std;

static ber::Type read_type(istream& is)
{
	unsigned char c;
	ber::Type type;
	if(is >> c) {//can read byte
		type.cls = static_cast<ber::Class>((c & 0b11000000) >> 6);
		type.pc = static_cast<ber::PC>((c & 0b00100000) >> 5);
		type.tag = static_cast<ber::Tag>(c & 0b00011111);
	} else {//reach EOF -> EOC return
		type.cls = ber::UNIVERSAL;
		type.pc = ber::PRIMITIVE;
		type.tag = ber::EOC;
	}
	return type;
}

static int read_length(istream& is)
{
	unsigned char c;
	is >> c;
	if(c & 0b10000000) {
		vector<unsigned char> v;
		for(int i = 0, j = c & 0b01111111; i < j; i++) {
			is >> c;
			v.push_back(c);
		}
		return bnd2mpz(v.begin(), v.end()).get_si();
	} else return c & 0b01111111;
}

static vector<unsigned char> read_value(istream& is, int len)
{
	unsigned char c; vector<unsigned char> v;
	for(int i=0; i<len; i++) {
		is >> c;
		v.push_back(c);
	}
	return v;
}

static Json::Value type_change(ber::Tag tag, vector<unsigned char> v)
{
	switch(tag) {
		case ber::EOC:
		case ber::BOOLEAN: return v[0] ? true : false;
		case ber::INTEGER: return (int)bnd2mpz(v.begin(), v.end()).get_si();
		case ber::BIT_STRING:
		case ber::OCTET_STRING:
		case ber::NUMERIC_STRING:
		{
			stringstream ss;
			for(auto a : v) ss << hex << +a;
			return ss.str();
		}
		case ber::NULL_TYPE:
		case ber::OBJECT_IDENTIFIER:
		case ber::OBJECT_DESCRIPTOR:
		case ber::EXTERNAL:
		case ber::REAL: return *(float*)v.data();
		case ber::ENUMERATED:
		case ber::EMBEDDED_PDV:
		case ber::RELATIVE_OID:

		default:
		{//strings
			stringstream ss;
			for(auto a : v) ss << a;
			return ss.str();
		}
		case ber::UTCTIME:
		case ber::GENERALIZED_TIME: return "yymmddhhmmssZ";
	}
}

static Json::Value read_constructed(istream& is, int length) 
{
	Json::Value jv;
	for(int i=0,l,start_pos=is.tellg(); is && (int)is.tellg()-start_pos<length; i++) {
		auto type = read_type(is);
		l = read_length(is);
		jv[i] = type.pc == ber::PRIMITIVE ? 
			type_change(type.tag, read_value(is, l)) : read_constructed(is, l);
	}
	return jv;
}

Json::Value der2json(istream& is) 
{
	Json::Value jv;
	struct ber::Type type;
	for(int i=0, l; (type = read_type(is)).tag != ber::EOC; i++) {
		l = read_length(is);
		jv[i] = type.pc == ber::PRIMITIVE ? 
			type_change(type.tag, read_value(is, l)) : read_constructed(is, l);
	}
	return jv;
}
