#include<gtkmm.h>
#include"server.h"

template <typename T> class Matrix;
struct Component
{
	char type, num;
	int x, y, w, h;
};

class AppServer : public Server
{
public:
	void app_start(std::function<std::string(std::string, Gtk::Window*)> f);

protected:
	std::string process(std::string s);

private:
	Matrix<char> win_def(std::string s);
	std::vector<Component> analyse_matrix(Matrix<char>& m);
};

