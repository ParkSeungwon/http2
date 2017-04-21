#pragma once
#include<vector>
#include<cmath>
#include<string>
#include<cassert>
#include<numeric>

template <typename T> class Matrix
{
public:
	Matrix(int w, int h) {
		width = w;
		height = h;
		arr = new T[h * w];
		for(int i=0; i<w * h; i++) arr[i] = 0;
	}
	T* operator[](int x) {
		assert(x > 0);
		return arr + (x -1) * height - 1;
	}
	T* data() {return arr;}
	Matrix(std::vector<std::vector<T>> v) : Matrix(v[0].size(), v.size()) {
		for(int x=0; x<width; x++) for(int y=0; y<height; y++) 
			arr[x * height + y] = v[y][x];
	}
	Matrix(const Matrix<T>& r) : Matrix(r.width, r.height) {
		for(int i=0; i<width * height; i++) arr[i] = r.arr[i];
	}
	virtual ~Matrix() {delete [] arr;}
	Matrix<T> operator+(const Matrix<T>& r) const {
		if(width != r.width || height != r.height) throw "Matrix size not match";
		Matrix<T> m(width, height);
		for(int i=0; i<width*height; i++) m.arr[i] = arr[i] + r.arr[i];
		return m;
	}
	Matrix<T> operator-(const Matrix<T>& r) const {
		if(width != r.width || height != r.height) throw "Matrix size not match";
		Matrix<T> m(width, height);
		for(int i=0; i<width*height; i++) m.arr[i] = arr[i] - r.arr[i];
		return m;
	}
	Matrix<T> operator*(const Matrix<T>& r) const {
		if(width != r.height) throw "Matrix size not match";
		Matrix<T> m(r.width, height);
		for(int x = 1; x <= r.width; x++) for(int y = 1; y <= height; y++) {
			auto v = row(y);
			m[x][y] = std::inner_product(v.begin(), v.end(), r.column(x), (T)0.0);
		}
		return m;
	}
	Matrix<T>& operator=(const Matrix<T>& r) {
		if(width != r.width || height != r.height) throw "Matrix size not match";
		for(int i=0; i<width*height; i++) arr[i] = r.arr[i];
		return *this;
	}
	Matrix<T>& operator*=(const Matrix<T>& r) {
		*this = *this * r;
		return *this;
	}
	Matrix<T> operator*(const T& r) const {return r * *this;}
	bool operator==(const Matrix<T>& r) const;
	friend Matrix<T> operator*(const T l, const Matrix<T>& r) {
		Matrix<T> m(r.width, r.height);
		for(int y=0; y<r.height; y++) {
			for(int x=0; x<r.width; x++) {
				m.arr[y*r.width+x] = l * r.arr[y*r.width+x];
			}
		}
		return m;
	}
	Matrix<T> inverse() const;
	Matrix<T> E() {
		if(width != height) throw "must be square matrix!";
		for(int x = 1; x <= width; x++) for(int y = 1; y <= height; y++) {
			if(x == y) (*this)[x][y] = 1;
			else (*this)[x][y] = 0;
		}
		return *this;
	}
	Matrix<T> gltranslate(T x, T y, T z) {
		if(width != 4 || height != 4) throw "should be 4x4";
		E();
		(*this)[4][1] = x;
		(*this)[4][2] = y;
		(*this)[4][3] = z;
		return *this;
	}
	Matrix<T> glrotateZ(T th) {
		if(width != 4 || height != 4) throw "should be 4x4";
		E();
		(*this)[1][1] = cos(th);
		(*this)[2][1] = -sin(th);
		(*this)[1][2] = sin(th);
		(*this)[2][2] = cos(th);
		return *this;
	}
	Matrix<T> glrotateX(T th) {
		if(width != 4 || height != 4) throw "should be 4x4";
		E();
		(*this)[2][2] = cos(th);
		(*this)[3][2] = -sin(th);
		(*this)[2][3] = sin(th);
		(*this)[3][3] = cos(th);
		return *this;
	}
	Matrix<T> glrotateY(T th) {
		if(width != 4 || height != 4) throw "should be 4x4";
		E();
		(*this)[1][1] = cos(th);
		(*this)[3][1] = -sin(th);
		(*this)[1][3] = sin(th);
		(*this)[3][3] = cos(th);
		return *this;
	}
	Matrix<T> glscale(T x, T y, T z) {
		if(width != 4 || height != 4) throw "should be 4x4";
		E();
		(*this)[1][1] = x;
		(*this)[2][2] = y;
		(*this)[3][3] = z;
		return *this;
	}

	Matrix<T> One() const;
	Matrix<T> surround(T wall = 0) const;
	template<typename T2>
	friend std::ostream& operator<<(std::ostream& o, const Matrix<T2>& r);
	int get_width() const {return width;}
	int get_height() const {return height;}
	
protected:
	T* arr;
	int width, height;

private:
	std::vector<T> row(int y) const{
		std::vector<T> v;
		T* p = arr + y - 1;
		for(int i=0; i<width; i++, p += height) v.push_back(*p);
		return v;
	}
	T* column(int x) const{
		return arr + (x - 1) * height;
	}
};

template <typename T> 
std::ostream& operator<<(std::ostream& o, const Matrix<T>& r) {
	for(int y=1; y<=r.height; y++) {
		for(auto& a : r.row(y)) o << a << ' ';
		o << std::endl;
	}
	return o;
}

