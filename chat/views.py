from django.shortcuts import get_object_or_404, render
from rest_framework.authtoken.views import ObtainAuthToken, APIView
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .models import Room, Profile, Message, Reaction
from rest_framework import status
from .serializer import MessageSerializer, RoomSerializer, ReactionSerializer

# Create your views here.

class LoginView(ObtainAuthToken):
        def post(self, request, *args, **kwargs):
            serializer = self.serializer_class(data=request.data,
                                            context={'request': request})
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            user = User.objects.get(pk=user.pk)
            user.profile.online = True
            user.save()
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email
            })
        
#Frontend ApiCall - Login:
    # async login(username: string, password: string) {
   
    #     try {
    #     let resp: any = await this.loginWithUsernameAndPassword(username, password);
    #     console.log(resp);
    #     localStorage.setItem('token', resp['token']);
    #     this.router.navigate(['summary']);
    #     } catch(e) {
    #     console.error(e);
    #     }
    # }

    # loginWithUsernameAndPassword(username: string, password: string) {
    #     const url = environment.baseURL + "/login/";
    #     const body = {
    #       "username": username,
    #       "password": password
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # }
        
#Frontend Service Interceptor - Token Header: 
# export class AuthInterceptorService implements HttpInterceptor{

#     constructor(private router: Router) { }

#     intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
#         const token = localStorage.getItem('token');

#         if (token) {
#         request = request.clone({
#             setHeaders: {Authorization: `Token ${token}`}
#         });
#         }

#         return next.handle(request).pipe(
#         catchError((err) => {
#             if (err instanceof HttpErrorResponse) {
#             if (err.status === 401) {
#                 this.router.navigateByUrl('/login');
#             }
#             }
#             return throwError( () => err);
#           })
#         );
#       }
#     }


class create_User(APIView):
    def post(self, request):
            if request.data['password'] == request.data['password_repeat']:
                user = User.objects.create_user(username=request.data['username'], email=request.data['email'], password=request.data['password'])
                user.save()
                return Response({'success': 'Benutzer erfolgreich erstellt.'}, status=status.HTTP_201_CREATED)
            else :
                return Response({'success': 'Passwörter stimmen nicht überein.'})

#Frontend Api Call - User create:
    # createUser(username: string, email: string, password: string, password_repeat: string  or UserModelClass!) {
    #     const url = environment.baseURL + "/createuser/";
    #     const body = {
    #       "username": username,
    #       "email": email,
    #       "password": password,
    #       "password_repeat": password_repeat
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # }            

class logout_view(APIView):
      authentication_classes = [TokenAuthentication]
      permission_classes = [IsAuthenticated]

      def post(self, request, format=None):
        try:
            request.user.profile.online = False
            request.user.save()
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#Frontend Api Call - User Logout: 
    # logout() {
    #     const url = environment.baseURL + "/logout/";
    #     return lastValueFrom(this.http.post(url));
    #     }

class RoomMessage_View(APIView):
      authentication_classes = [TokenAuthentication]
      permission_classes = [IsAuthenticated]

      def post(self, request, format=None):
            match request.data['methode']:
                case "get":
                    messages = Message.objects.filter(room=request.data['room'])
                    serializer = MessageSerializer(messages, many=True)
                    return Response(serializer.data)    
                 
                case "post":
                    room_id = request.data.get('room')
                    room = get_object_or_404(Room, pk=room_id)
                    message = Message.objects.create(sender=request.user, message=request.data['message'], room=room)
                    message.save()
                    return Response({'success': 'Nachricht erfolgreich an Raum abgeschickt.'}, status=status.HTTP_201_CREATED)

#Frontend Api Call - Message get:
    # getRoomMessages(room: number) {
    #     const url = environment.baseURL + "/roommessage/";
    #     const body = {
    #       "room": room,
    #       "methode": "get"
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # } 
                
#Frontend Api Call - Message create:
    # sendRoomMessage(room: number, message: string) {
    #     const url = environment.baseURL + "/roommessage/";
    #     const body = {
    #       "message": message,
    #       "room": room,
    #       "methode": "post"
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # } 

      
class DirectMessage_View(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        match request.data['methode']:
            case "get":
                messages = Message.objects.filter(sender=request.user)
                serializer = MessageSerializer(messages, many=True)
                return Response(serializer.data)
    
            case "post":
                reciever_id = request.data.get('reciever')
                reciever = get_object_or_404(User, pk=reciever_id)
                message = Message.objects.create(sender=request.user, message=request.data['message'], reciever=reciever)
                message.save()
                return Response({'success': 'Nachricht erfolgreich abgeschickt.'}, status=status.HTTP_201_CREATED)

#Frontend Api Call - Message get:
    # getMessages(reciever: number) {
    #     const url = environment.baseURL + "/direct/";
    #     const body = {
    #       "reciever": reciever,
    #       "methode": "get"
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # } 
                
#Frontend Api Call - Message create:
    # sendMessage(reciever: number, message: string) {
    #     const url = environment.baseURL + "/direct/";
    #     const body = {
    #       "message": message,
    #       "reciever": reciever,
    #       "methode": "post"
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # } 
      
class Room_View(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        match request.data['methode']:
            case "get":
                rooms = Room.objects.all()
                serializer = RoomSerializer(rooms, many=True)
                return Response(serializer.data)
    
            case "post":
                try:
                    room = Room.objects.create(roomName=request.data['roomName'], description=request.data['description'], created_by=request.user)
                    room.save()
                    return Response({'success': 'Raum erfolgreich erstellt.'}, status=status.HTTP_201_CREATED)
                except:
                    return Response({'success': 'Fehler'})
                
#Frontend Api Call - Rooms get:
    # getRooms(reciever: number) {
    #     const url = environment.baseURL + "/direct/";
    #     const body = {
    #       "methode": "get"
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # } 
                
#Frontend Api Call - Message create:
    # createRoom(roomName: string, description: string) {
    #     const url = environment.baseURL + "/direct/";
    #     const body = {
    #       "roomName": roomName,
    #       "description": description,
    #       "methode": "post"
    #     };
    #     return lastValueFrom(this.http.post(url, body));
    # } 