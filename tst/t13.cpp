#include<thread>
#include<unistd.h>
#include<iostream>
using namespace std;
int main()
{
	int k = 0;
	while(1) {
		if(!fork()) cout << k++ << endl;
		this_thread::sleep_for(1s);
	}
}
