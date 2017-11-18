# C++ Web development Framework with STATE(CWFS)

License : GNU GPL V2.0

## What is CWFS

Web server is stateless. It gives much difficulty in backend programming and results in heavy use of
cookies. I made a programming environment that can handle this situation. There are two processes
running. One is middle server. The other is Web server. Middle server will maintain connections to
web server, and will allocate web browser requests to a proper connection. Now, web server has virtual
environment of being continuously connected to a web browser.

Thus a web server with state is made. We can use variables across web pages. We can use full power
of C++ programming in Backend programming. Also the complicatedness of web programming is
lessened. By just defining a web site class we can do the job.

## Directory Structure

framework : CWFS framework(main feature)

database : classes about database access(dependency : mysqlcppconn, libjsoncpp)

src : website backend

html, js, jpg files on root : website frontend

## Minimal Website
a.html
```
<html>
<body>
  <form action ="a.html" method="post">
    <input type="text" value="ENTER" name="num" >
    <input type ="submit" >
  </form>
</body>
</html >
```
minimal server side programming
```
#include "server.h"
#include "htmlserver.h"
class MyWebSite : public WebSite
{
protected :
  virtual void process() {
    if(requested_document_ == "a.html")
      if(nameNvalue_["num"] != "")
        swap("ENTER" , "you entered" + nameNvalue_["num"]);
  }
};

using namespace std;
int main()
{
  MyWebSite f;
  Server sv;
  sv.start(f);
}
```

## How it works
<ul>
<li>Any time a page is requested, it is stored in variable requested_document_.
<li>And all the parameters are stored in std::map<string, string> nameNvalue_.
<li>If the framework can find the requested document(i.e index.html) on the default directory, it is stored in the variable content_.
<li>Just before the requested document in the content_ is transferred to the browser, process() method is called.
<li>If you want to change the content_ (ie. after database access), you can override process() method in your class.
  </ul>
