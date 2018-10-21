#include"log.h"
using namespace std;

Log *Log::plog_ = nullptr;

Log *Log::get_instance()
{
	if(!plog_) plog_ = new Log();
	return plog_;
}

Log::Log() : log_file_{"/tmp/log", ios::app | ios::out}
{ }

Log::~Log()
{
	if(plog_) delete plog_;
}

Log& Log::operator<<(ostream& (*manipulators)(ostream&)) {
	clog << manipulators;
	log_file_ << manipulators;
	return *this;
}
