from CommunicationServices import server_ssl
if __name__ == "__main__":
    try:
        print("Starting server...")
        #clear_list()
        server = server_ssl()
        server.build_listen()
        print("test2")
    except KeyboardInterrupt:
        print("Server is shutting down...")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        print("Server has been stopped.")
        exit(0)