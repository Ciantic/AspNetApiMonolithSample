namespace AspNetApiMonolithSample.Models
{
    public class Thingie : IEntity<int>
    {
        public int Id { get; set; } = 0;
        
        public string Name { get; set; } = "";
    }
}
