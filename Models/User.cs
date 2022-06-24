#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LoginRegistration.Models;

public class User
{  
    [Key]
    public int UserId {get;set;}
    [Required]
    public string Username {get;set;}
    [Required]
    [EmailAddress]
    public string Email  {get;set;}
    [Required]
    [MinLength(8)]
    [DataType(DataType.Password)]
    public string Password {get;set;}
    [NotMapped]
    [Compare("Password")]
    public string PassConfirm {get;set;}
    public DateTime CreatedAt = DateTime.Now;
    public DateTime UpdatedAt = DateTime.Now;
}