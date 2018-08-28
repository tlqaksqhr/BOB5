#include <stdio.h>


int exit_parse(char *str)
{
	char *s_exit = "exit";
	char *parse_buf,*str_buf;
	parse_buf = str;
	int count;
	count = 0;

	str_buf = s_exit;

	while( (*parse_buf == *str_buf) && (*parse_buf != '\0') && (*str_buf != '\0') )
	{
		parse_buf++;
		str_buf++;
		count++;
	}

	if(count != 4)
		return 0;
	else
		return 4;
}

int print_prompt(void)
{
	printf(" $ ");
	printf(" # ");

	return 0;
}

int main(int argc,char **argv)
{
	char c;
	char *line_buf[1024];
	char *lp;
	lp = line_buf;

	printf(" $ ");

	while( c = getchar() )
	{
		*lp = c;
		lp++;
		if( c == '\n'){
			*lp = '\0';
			printf("%s",line_buf);
			if(exit_parse(line_buf))
				break;
			printf(" $ ");
			lp = line_buf;
		}
	}

	return 0;

}
