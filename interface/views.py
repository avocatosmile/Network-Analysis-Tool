from django.shortcuts import render ,redirect
from django.http import HttpResponse 
from django.contrib.auth import authenticate, logout
from django.contrib.auth import login as Lg
from django.contrib import messages
from django.template import loader
from interface.scripts.functions import *
from interface.scripts.NetworkScript import *
from django.contrib.auth.models import User
from .models import file 
from django.contrib.auth import get_user_model
from .forms import CreateUserform ,UploadFileForm
from datetime import date
from datetime import datetime

#from . import analysing
usercounts=[]
userID=""
fileID=""
# Create your views here.

def UploadFiles(request):
     
     global userID
     global fileID
     global file2ID
     print("finnaallly", userID )
     vuln=[]
     if request.method =="POST":
     
         form = UploadFileForm(request.POST ,request.FILES)
         newfile =request.FILES['file']
         print(newfile)
         newEntry = file.objects.create(File=newfile)
         newEntry.save()
         Identify =newEntry.FileId
         data = file.objects.get(FileId=Identify)
         mm = data.File
         fileID=Identify
         print("why" ,mm)
         map= makemap(str(newfile))
         
         DDOSattk= DDosAttack(str(newfile))
         Portflod= Portflooding(str(newfile))
         sus=suspicouspkt(str(newfile))
         mostactive=mostactiveips(str(newfile))
         protocal1 ,protocal2 ,protocal3 ,protocal4 , protocal5=protocols(str(newfile))
         sourceIP, destinationIP, sourcemac, destinationmac , sourceIParp, destinationIParp, sourcemacarp, destinationmacarp = netstat(str(newfile))
   
         data = file.objects.get(FileId=Identify)
         data.Networkmap = map
         data.UserId=userID
         data.DDos=DDOSattk
         data.susips=sus
         data.portflooding=Portflod
         data.mostactiveadd=mostactive
         data.arp=protocal1
         data.tcp=protocal2
         data.udp=protocal3
         data.icmp=protocal4
         data.ssl=protocal5
         data.SourceIP=sourceIP
         data.destinationIP=destinationIP
         data.Sourcemac=sourcemac
         data.destinationmac=destinationmac
         data.SourceIParp=sourceIParp
         data.destinationIParp=destinationIParp
         data.Sourcemacarp=sourcemacarp
         data.destinationmacarp=destinationmacarp

         data.save()
        
         
         
       #  print(str(newEntry.pk)+"has been added"+map)
         context ={'File':'data'}
         print(context)
         
         return redirect('/display' )
     else:
         form = UploadFileForm()
     return render(request ,'upload_files.html',{'form':form})
     
    
def display(request):
     global userID
     print("this is the user ID",userID)
     Data = file.objects.all()
     global fileID
     global file2ID
     print("this",fileID)
     Filedata = file.objects.get(FileId=fileID)
     file2ID=Filedata.FileId
     x=Filedata.mostactiveadd
     mostactiveips= x.split(',')
     ddos= Filedata.DDos
     portflooding = Filedata.portflooding
     mostactiveips[1]=mostactiveips[1] 
     susips = Filedata.susips
     if(len(susips) > 3):
         susips=susips +" This address has been sending multiple messages within your network further investigation is adviced"
    
     protocal1="ARP packets : "+ Filedata.arp
     protocal2="TCP packets : "+Filedata.tcp
     protocal3="UDP packets : "+Filedata.udp
     protocal4="ICMP packets : "+Filedata.icmp
     protocal5="SSL packets : "+Filedata.ssl
     print("cooow", ddos)
     if (str(ddos) == "True"):
          ddos_string=" DDOS attack was detected in this  network!"
     else:
          ddos_string=" DDOS attack was not detected in this network "

     if (str(portflooding) == "True"):
          port_string=" Port Flooding was detected in this  network!"
     else:
          port_string=" Port Flooding was not detected in this network "
     test = "media/example.pcapng.png"
     print(ddos)
     context ={'susips':susips,'File':Filedata  , 'port':port_string , 'ddos':ddos_string , 'test':test , 'protocal1':protocal1,'protocal2':protocal2 ,'protocal3':protocal3 ,'protocal4':protocal4 ,'protocal5':protocal5 , 'MOS':mostactiveips[1]}


     return render(request ,'Dashboard.html',context)
def ipdisplay(request):
    
     global file2ID
     Data = file.objects.all()
     Filedata = file.objects.get(FileId=  file2ID )
    
     
     source =Filedata.SourceIP
     cringe= source.split(',')

     sourcemac =Filedata.Sourcemac
     cringemac= sourcemac.split(',')

     

     destination = Filedata.destinationIP
     dest=destination.split(',')

     destinationmac = Filedata.destinationmac
     destmac=destinationmac.split(',')

     sourcearp =Filedata.SourceIParp
     cringearp= sourcearp.split(',')

     sourcemacarp =Filedata.Sourcemacarp
     cringemacarp= sourcemacarp.split(',')

     

     destinationarp = Filedata.destinationIParp
     destarp=destinationarp.split(',')

     destinationmacarp = Filedata.destinationmacarp
     destmacarp=destinationmacarp.split(',')
     
     size=len(cringe)
     print(size)
     context ={'source':cringe,'sourcemac':cringemac, 'dest':dest ,'destmac':destmac ,'destmacarp':destmacarp ,'sourcearp':cringearp,'sourcemacarp':cringemacarp, 'destarp':destarp ,'destmacarp':destmacarp }
     return render (request , 'Newdash.html' ,context)


def about(request):
    
     return render(request ,'about.html')

def dashboard(request):
   
     return render(request ,'Dashboard.html' )

     
def login(request):
     
     if request.method == 'POST':
        username =  request.POST.get('username')
        password =request.POST.get('password')
        global userID
        userID= "sean"
        print("here" +username+ password)
      
        user = authenticate(request ,username=username , password=password)
        if  username == "Admin" :
         if  password== "root":
           return redirect('/ad')
        x= user
        print (x)
        if user is not None:
          Lg(request ,user)
          context ={'user':'username'}
          
          return redirect('/dashboard' ,context)
        

        else:
          messages.success(request,'wrong password or username try again ')
     context ={}

     return render(request ,'login.html' ,context)

def signup(request):
     form = CreateUserform()

     if request.method == 'POST':
          form = CreateUserform(request.POST)
          
          if form.is_valid():
               form.save()
               username= form.cleaned_data.get('username')
               
               
             
               messages.success(request,'Account was created for '+username)
               return redirect('/login')
          else:
               
               messages.success(request,'incorrect details retry ')
     context ={'form':form}
     return render(request ,'signup.html',context) 


def adminsignup(request):
     form = CreateUserform()

     if request.method == 'POST':
          form = CreateUserform(request.POST)
          
          if form.is_valid():
               form.save()
               username= form.cleaned_data.get('username')
               
               
             
               messages.success(request,'Account was created for '+username)
               return redirect('/ad')
          else:
               
               messages.success(request,'incorrect details retry ')
     context ={'form':form}
     return render(request ,'signupadmin.html',context) 

def admin(request):
 


  users= get_user_model().objects.all()
  x= 2
  context = {
    'users': users,
    
  }
  print(users)
  
  return render(request ,'Admin.html',context)


def delete(request):
     if request.method == 'POST':
        username =  request.POST.get('username')
        Id =request.POST.get('Id')
        
        print("here" +username)

        entry= User.objects.get(username=username)
       

        if entry:
          
          
          entry.delete()

          context ={'Duser':'Dusername'}
          return redirect('/ad' ,context)
        

        else:
          messages.success(request,' username does not exist ')
          return redirect('/ad' ,context)
     context ={}
     return render(request ,'deleteuser.html')


def Reports(request):
     users= get_user_model().objects.all()
     Data = file.objects.all() 
     if request.method == 'POST':
        type =  request.POST.get('Reports')
        if (type == "User_report"):
             context ={'users':users}
             return render(request ,'show.html', context)
        elif(type == "Network_report") :
               context ={'data':Data}
               return render(request ,'show2.html', context)
        
     return render(request ,'Report.html')
































