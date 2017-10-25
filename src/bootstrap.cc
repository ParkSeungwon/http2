#include<vector>
#include"bootstrap.h"
using namespace std;

string BootStrapServer::carousel(vector<string> img, vector<string> desc, vector<string> href)
{//if you want more than 1 carousel in a page, you should change the id
	string r = R"(
<div id="myCarousel" class="carousel slide" data-ride="carousel">
  
  <!-- Indicators -->
  <ol class="carousel-indicators">
    <li data-target="#myCarousel" data-slide-to="0" class="active"></li>)";
	for(int i=1; i<img.size(); i++) 
		r += "<li data-target=\"#myCarousel\" data-slide-to=\"" + to_string(i) + "\"></li>";
	r += R"(
  </ol>
  
  <!-- Wrapper for slides -->
  <div class="carousel-inner">)";
	for(int i=0; i<img.size(); i++) {
		r += "<div class=\"item" + string(i ? "" : " active") + "\">";
		r += "<a href=\"" + href[i] + "\"><img src=\"" + img[i] + "\"></a>";
		r += "<div class=\"carousel-caption\"><p>" + desc[i] + "</p></div>";
		r += "</div>";
	}
  	r += R"(
  </div>
  
  <!-- Left and right controls -->
  <a class="left carousel-control" href="#myCarousel" data-slide="prev">
    <span class="glyphicon glyphicon-chevron-left"></span>
    <span class="sr-only">Previous</span>
  </a>
  <a class="right carousel-control" href="#myCarousel" data-slide="next">
    <span class="glyphicon glyphicon-chevron-right"></span>
    <span class="sr-only">Next</span>
  </a>
</div>
)";
	return r;
}
