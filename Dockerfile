FROM 542401451332.dkr.ecr.us-west-2.amazonaws.com/gothambuild:latest

EXPOSE 8000
CMD ["/root/.cargo/bin/cargo", "run", "--release"]



