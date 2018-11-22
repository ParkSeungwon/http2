#include<vector>
#include<fstream>
#include"util.h"
using namespace std;

void serialize(const vector<string>& v, string filename) 
{
	ofstream f(filename);
	f << v.size() << ' ';
	for(const string& s : v) f << s.size() << ' ';
	for(const string& s : v) f << s;
}

vector<string> deserialize(string filename)
{
	ifstream f(filename);
	int n;
	f >> n;
	int sz[n];
	for(int i=0; i<n; i++) f >> sz[i];
	char c;
	f >> noskipws >> c;//consume trailing ' '

	vector<string> v;
	for(int i=0; i<n; i++) {
		string s;
		for(int j=0; j<sz[i]; j++) {
			f >> noskipws >> c;
			s += c;
		}
		v.push_back(s);
	}
	return v;
}		

string psstm(string command)
{//return system call output as string
	string s;
	char tmp[1000];
	FILE* f = popen(command.c_str(), "r");
	while(fgets(tmp, sizeof(tmp), f)) s += tmp;
	pclose(f);
	return s;
}


string param(const string& post, const string& par) 
{//env(QUERY_STRING), parameter 
	int pos = post.find(par);
	pos = pos + par.length() + 1;
	int end = post.find('&', pos);
	
	string s = post.substr(pos, end - pos);
	for(pos = s.find('+', 0); pos != string::npos; pos = s.find('+', pos))
		s.replace(pos, 1, 1, ' ');
	for(pos = s.find('%', 0); pos != string::npos; pos = s.find('%', pos))
		s.replace(pos, 3, 1, (char)stoi(s.substr(pos + 1, 2), nullptr, 16));
	return s;
}

map<string, string> parse_post(istream& post)
{
	map<string, string> m;
	string s, value;
	while(getline(post, s, '&')) {
		int pos = s.find('=');
		value = s.substr(pos+1);
		for(auto& a : value) if(a == '+') a = ' ';
		for(int i = value.find('%'); i != string::npos; i = value.find('%', i))
			value.replace(i, 3, 1, (char)stoi(value.substr(i + 1, 2), nullptr,16));
		if(value.back() == '\0') value.pop_back();
		m[s.substr(0, pos)] = value;
	}
	return m;
}

pair<string, string> parse_multiform(istream& is)
{

}
