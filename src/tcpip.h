//tcpip.h class definition
#include <string>
#include <thread>
#include <condition_variable>
#include <vector>
#include <arpa/inet.h>
#include <deque>
#include <mutex>

class Tcpip ///  TCP IP Header 
{ 
public:
	Tcpip(int port);
	virtual ~Tcpip();
	void send(std::string s);
	std::string recv();

protected:
	int server_fd;///<server_fd입니다.
	int client_fd;
	struct sockaddr_in server_addr, client_addr;
	char buffer[1024];

private:
};

class Connection : public Tcpip
{
public:
	Connection(std::function<std::string(std::string)> f);
	std::deque<std::string> q;
	
protected:
	thread thi, tho;
	std::mutex mtx;
	std::condition_variable cv;
	std::function<std::string(std::string)> functor;

private:
	bool finish = false;
	void recvf();
	void sendf();
};

class Client : public Tcpip
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
};

class Server : public Tcpip
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue = 10, std::string e = "end");
	void start(std::function<std::string(std::string)> functor);
	virtual ~Server();
	
protected:
	static void timed_out(int sig);
	std::string end_string;
	unsigned int time_out;
	std::string recv(int client_fd);
	void send(std::string, int client_fd);

private:
	void handle_connection(std::function<std::string(std::string)> f, int fd);
	void qrecv(int fd, std::deque<std::string>& q, std::mutex& mtx, std::condition_variable& cv);
	std::vector<std::thread> connections;
};
