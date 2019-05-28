#include<iostream>
#include"framework/server.h"//Server class
#include"framework/website.h"//WebSite class
using namespace std;

int main(int ac, char** av)
{
	WebSite my_site{"site_html"};//directory name relative to your exe file
							//directory contains html files
	Server sv{2000};//port number
	cout << "opening port " << 2000 << endl;
	sv.start(my_site);//go infinite loop
}

