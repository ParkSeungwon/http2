#include<algorithm>
#include<cassert>
using namespace std;

int main()
{
	int a[] = {3,2,1,4,5,6,3,4};
	sort(a, a+8);
	for(int i=0; i<7; i++) assert(a[i] <= a[i+1]);
}

