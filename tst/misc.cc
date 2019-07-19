#include<catch.hpp>
using namespace std;

struct A {
	int i;
	int p[];
};

TEST_CASE("sizeof key[]") {
	REQUIRE(sizeof(A) == sizeof(int));
}
