#include<fstream>
using namespace std;

int main()
{
	ifstream f1("server-cert.pem");
	ofstream f2("tls/cert.h");
	f2 << R"(const char certificate[] = R"cert()";
	for(char c; f1 >> noskipws >> c; f2 << noskipws << c);
	f2 << R"str()cert";)str";
}

