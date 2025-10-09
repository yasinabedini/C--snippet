#include <iostream>

extern "C" int hello(void*, void*);

int sum(int a, float b, int c, int d) {
	std::cout << c;
	return 5;
}

int m() {
	return 2;
}

int main() {

	hello(sum, m);
	int a = 5;
}