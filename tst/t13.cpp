#include<thread>
#include<iostream>
using namespace std;
int main()
{
	thread th{[]() {while(1) cout << this_thread::get_id();}};
	cout << th.get_id();
	this_thread::sleep_for(10s);

}
