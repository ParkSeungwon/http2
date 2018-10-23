#include<fstream>
#include<iostream>
#define LOG (*Log::get_instance()<<'['<<__FILE__<<"] {"<<__func__<<"} L"<<__LINE__<<" | ")

class Log
{
public:
	static Log *get_instance();
	template<class T> Log& operator<<(T r) {
		std::clog << r;
		log_file_ << r;
		return *this;
	}
	Log& operator<<(std::ostream& (*manipulators)(std::ostream&));
	~Log();

protected:
	std::ofstream log_file_;

private:
	static Log *plog_;
	Log();
};
