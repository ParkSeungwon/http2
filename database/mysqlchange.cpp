#include"mysqldata.h"
using namespace std;

string base64_encode(vector<unsigned char> v);
int main()
{
	SqlQuery sq;
	sq.connect("localhost", "dndd", "dndddndd", "dndd");
	for(const char *p : {"Sample"}) {
		sq.select(p, "where title <> '코멘트임.' and page <> 0 order by num, page, edit desc");
		sq.group_by({"num", "page"});
		int k = 1;
		for(const auto &a : sq) {
			string s = a["contents"].asString();
			vector<uint8_t> v{s.begin(), s.end()};
			s = base64_encode(v);
			cout << k++ << " : ";
//			int num = a["num"].asInt();
//			int page = a["page"].asInt();
//			string email = a["email"].asString();
//			string title = a["title"].asString();
//			string contents = a["contents"].asString();
//			string date = a["date"].asString();
//			int edit = a["edit"].asInt();
//
//			printf("%d %d %s %s %s %d\n", num, page, email.data(), title.data(), date.data(), edit);
			sq.insert(a["num"].asInt(), a["page"].asInt(), a["email"].asString(), a["title"].asString(), s, a["date"].asString(), a["edit"].asInt() + 1);
		}
	}
}

