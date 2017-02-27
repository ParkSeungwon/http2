#include<string>
#include<iostream>
#include<thread>
#include"asyncqueue.h"
using namespace std;
class Provider
{
public:
	string operator()() {
		this_thread::sleep_for(chrono::seconds(1));
		return to_string(i++);
	}
private:
	int i = 0;
} provider;

void consumer(string s) {
	cout << s << endl;
}

int main()
{
	string s;
	AsyncQueue<string> aq{provider, consumer};
	while(cin >> s) aq.push_back(s);
}
