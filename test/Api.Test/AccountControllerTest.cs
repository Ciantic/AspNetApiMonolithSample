using AspNetApiMonolithSample.Controllers;
using Xunit;

namespace AspNetApiMonolithSample.Test
{
    public class AccountControllerTest
    {
        [Fact]
        public void PassingTest()
        {
            Assert.Equal(4, Add(2, 2));
        }

        int Add(int x, int y)
        {
            return x + y;
        }
    }
}