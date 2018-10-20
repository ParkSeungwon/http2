#include<typeinfo>
#include<iostream>
#include"option.h"
using namespace std;

CMDoption::CMDoption(initializer_list<tuple<const char*, const char*, any>> options)
{
	options_ = options;
}

bool CMDoption::args(int ac, char **av)
{//return false if arguments are wrong
	any *val;
	for(int i=1; i<ac; i++) {
		if(av[i][0] == '-') {
			int match=0;
			for(auto& [param, desc, value] : options_) {
				if(!strncmp(&av[i][1], param, strlen(av[i])-1)) {
					match++;
					val = &value;
					if(value.type() == typeid(bool)) value = true;
				}
			}
			if(match != 1) {
				cout << "usage : " << av[0] << " [options] [value] " << endl;
				cout << "you should use at least distinguishable amount of characters of options\nif default is boolean you don't need value\navailable options\n";
				print_help();
				return false;
			}
		} else {
			if(val->type() == typeid(int)) *val = atoi(av[i]);
			else if(val->type() == typeid(double) || val->type() == typeid(float))
				*val = atof(av[i]);
			else if(val->type() == typeid(const char*)) *val = (const char*)av[i];
		}
	}
	return true;
}

void CMDoption::print_help()
{
	for(auto& [pa, desc, val] : options_) {
		cout << '-' << pa << " : " << desc << "(default ";
		if(val.type() == typeid(int)) cout << any_cast<int>(val);
		else if(val.type() == typeid(double)) cout << any_cast<double>(val);
		else if(val.type() == typeid(float)) cout << any_cast<float>(val);
		else if(val.type() == typeid(const char*)) cout << any_cast<const char*>(val);
		else if(val.type() == typeid(bool)) cout << "false";
		cout << ')' << endl;
	}
}
