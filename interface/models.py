from django.db import models
from django.contrib.auth.models import User
from django.utils.safestring import mark_safe
class file(models.Model):
    FileId=models.AutoField(primary_key=True)
    UserId=models.CharField(max_length=256,null=True)
    File=models.FileField(null=True)
    Networkmap=models.ImageField(upload_to='images/')
    SourceIP=models.CharField(max_length=256,null=True)
    destinationIP=models.CharField(max_length=256,null=True)
    Sourcemac=models.CharField(max_length=256,null=True)
    destinationmac=models.CharField(max_length=256,null=True)
    SourceIParp=models.CharField(max_length=256,null=True)
    destinationIParp=models.CharField(max_length=256,null=True)
    Sourcemacarp=models.CharField(max_length=256,null=True)
    destinationmacarp=models.CharField(max_length=256,null=True)
    arp=models.CharField(max_length=256,null=True)
    udp=models.CharField(max_length=256,null=True)
    icmp=models.CharField(max_length=256,null=True)
    ssl=models.CharField(max_length=256,null=True)
    tcp=models.CharField(max_length=256,null=True)
    mostactiveadd=models.CharField(max_length=256,null=True)
    susips=models.CharField(max_length=256,null=True)
    portflooding=models.CharField(max_length=256,null=True)
    DDos=models.CharField(max_length=256,null=True)
   
    
    def __str__(self) :
        return self.File ,self.Name 
    def image_tag(self): # new
        return mark_safe('<img src="/../../media/%s" width="150" height="150" />' % (self.Networkmap))
 
class interfaceUser( models.Model ) :
    def __unicode__( self ) :
       return self.user.username

    user    = models.ForeignKey( User ,on_delete=models.CASCADE)
    logincont   = models.CharField( max_length = 135, blank = True )








# Create your models here.
