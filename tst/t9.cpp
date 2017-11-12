#include"mysqldata.h"
using namespace std;

int main()
{
	SqlQuery sq;
	sq.connect("localhost", "shopping_mall", "shopping_mall", "shopping_mall");
	sq.select("회원");
}

