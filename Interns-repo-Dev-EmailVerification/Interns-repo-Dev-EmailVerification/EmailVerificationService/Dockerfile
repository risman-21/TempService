FROM mcr.microsoft.com/dotnet/sdk:8.0 AS dev2

WORKDIR /app

COPY . ./

RUN dotnet restore

EXPOSE 80

CMD ["dotnet", "watch", "run", "--urls=http://0.0.0.0:80"]
