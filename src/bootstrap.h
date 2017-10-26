#pragma once
#include<map>
#include<string>
#include"htmlserver.h"
using namespace std;

class BootStrapServer : public HTMLServer
{//class that makes writing bootstrap elements easy
protected:
	static std::string carousel(std::vector<std::string> img, std::vector<std::string> desc, std::vector<std::string> href);
};

