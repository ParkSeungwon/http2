#include<iostream>
#include<sstream>
#include<string>
#include<cstring>
#include"server.h"
#include"util.h"
using namespace std;

class Functor
{
public:
	int i=0;
	string operator()(string s) {
		cout << s << endl;
		if(!strncmp(s.data(), "GET", 3)) content =  R"(
<html>
 <head>
  <meta charset="utf-8" />
  <meta content="width=device-width, initial-scale=1, shrink-to-fit=no" name="viewport" />
  <link crossorigin="anonymous" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" rel="stylesheet" />
  <link crossorigin="anonymous" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" rel="stylesheet" />
  <script crossorigin="anonymous" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js">
  </script>
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js">
  </script>
  <style type="text/css" src="dndd.css"></style>
  <script src="dndd.js"></script>
  <title>
   토론과 민주적인 의사 결정
  </title>
 </head>
 <body>
 한룰.
 <script>
	$(document).ready(function(){
	var json = {"fa" : "fdsfsfd", "fddsf":"fsfsfsfsd"};
$.post("login.cgi", json, function(){
		replace.innerHTML = data;
});
});
</script>
<p id="replace"></p>
 </body>
</html>
)";
		else if(!strncmp(s.data(), "POST", 4)) {
			stringstream ss;
			ss << s;
			while(s != "\r") getline(ss, s);//pass header part
			auto m = parse_post(ss);
			for(auto el : m) content += el.first + ':' + el.second + '\n';
		}
		i++;
		
		string re = header + to_string(content.size()) + "\r\n\r\n" + content;
		cout << "sending" << endl << re;
		return re;
	}

private:
	string header = R"(
HTTP/1.1 200 OK
Content-Type: text/html;
Content-Length: )";
	string content;
} f;

int main(int ac, char** av)
{
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port};
	sv.start(f);
}
