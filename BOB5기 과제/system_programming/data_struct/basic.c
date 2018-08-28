#include <stdio.h>

struct foobar
{
	int foo;
	char bar;
	char boo;
};

int main(int argc,char **argv)
{
	struct foobar tmp;

	printf("address of &tmp : %p\n\n",&tmp);
	printf("address of tmp->foo = %p\t offset of tmp->foo = %lu\n",&tmp.foo,((unsigned long)&((struct foobar *)0)->foo));
	printf("address of tmp->foo = %p\t offset of tmp->foo = %lu\n",&tmp.bar,((unsigned long)&((struct foobar *)0)->bar));
	printf("address of tmp->foo = %p\t offset of tmp->foo = %lu\n",&tmp.boo,((unsigned long)&((struct foobar *)0)->boo));

	return 0;
}
