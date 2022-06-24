#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LoginRegistration.Models;

public class LogUser
{  
    [EmailAddress]
    [Required]
    public string LogEmail  {get;set;}
    [Required]
    [MinLength(8)]
    [DataType(DataType.Password)]
    public string LogPassword {get;set;}
}
