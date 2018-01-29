#include"crypt.h"
using namespace std;

static ber::Type read_type(istream& is)
{
	unsigned char c;
	is >> c;
	ber::Type type;
	type.cls = (c & 0b11000000) >> 6;
	type.pc = (c & 0b00100000) >> 5;
	type.tag = c & 0b00011111;
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
		return bnd2mpz(v.begin(), v.end());
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

static Json::Value read_constructed(istream& is, int length) 
{
	Json::Value jv;
	for(int i=0; length > 0; i++) {
		auto type = read_type(is);
		int l = read_length(is);
		length -= l;
		if(type.pc == ber::CONSTRUCTED) jv[i] = read_constructed(is, l);
		else {
			auto v = read_value(is, l);
			switch(type.tag) {
				case ber::EOC:
				case ber::BOOLEAN:
					jv[i] = v[0] ? true : false;
					break;
				case ber::INTEGER: 
				{
					int* p = (int*)v.data();
					jv[i] = *p;
					break;
				}
				case ber::BIT_STRING:
				case ber::OCTET_STRING:
				case ber::NUMERIC_STRING:
				{
					stringstream ss;
					for(auto a : v) ss << hex << +a;
					jv[i] = ss.str();
					break;
				}
				case ber::NULL_TYPE:
				case ber::OBJECT_IDENTIFIER:
				case ber::OBJECT_DESCRIPTOR:
				case ber::EXTERNAL:
				case ber::REAL:
				{
					float* p = (float*)v.data();
					jv[i] = *p;
					break;
				}
				case ber::ENUMERATED:
				case ber::EMBEDDED_PDV:
				case ber::RELATIVE_OID:

				case ber::UTF8STRING:
				case ber::PRINTABLE_STRING:
				case ber::T61_STRING:
				case ber::VIDEOTEX_STRING:
				case ber::IA5_STRING:
				case ber::GRAPHIC_STRING:
				case ber::VISIBLE_STRING:
				case ber::GENERAL_STRING:
				case ber::UNIVERSAL_STRING:
				case ber::CHARACTER_STRING:
				case ber::BMP_STRING:
				{
					stringstream ss;
					for(auto a : v) ss << a;
					jv[i] = ss.str();
					break;
				}
				case ber::UTCTIME:
				case ber::GENERALIZED_TIME:
					jv[i] = 
			}
		}
	}
	return jv;
}

string der2json(istream& is) 
{
	unsigned char c;
	auto type = read_type(is);
	int length;
	if(type.pc == ber::PRIMITIVE) length = read_length(is);
