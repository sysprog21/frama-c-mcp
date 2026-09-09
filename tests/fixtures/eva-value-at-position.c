int compute(int n)
{
    int total = 0;
    if (n > 3) {
        total = n * 2;
    }
    return total;
}

int main(void)
{
    return compute(5);
}
