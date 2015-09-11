#starttime	seconds	ctime	dtime	ttime	wait
#Thu Sep 10 21:01:43 2015	1441911703	0	0	0	0
#Thu Sep 10 21:01:40 2015	1441911700	0	0	0	0
#Thu Sep 10 21:01:40 2015	1441911700	0	0	0	0

#data <- read.table("temp.plot.file", header=TRUE, sep=" ", row.names="id")
#data <- read.table("temp.plot.file", sep="\t", header=TRUE)
data <- read.table("tcp-all.files.data-22-47-03@11-09-2015", sep="\t", header=TRUE)

g_range <- range(0, data[,3], data[,4], data[,5], data[,6]) 

png(filename="plots/tcp.png")
#plot(ecdf(data[,3]), col="blue", ylim=g_range, axes=FALSE)
plot(ecdf(data[,3]), col="blue", ann=FALSE)
title(xlab="Time(ms)")
title(main="ECDF times without module")
box()

lines(ecdf(data[,4]), col="red")
lines(ecdf(data[,5]), col="green")
lines(ecdf(data[,6]), col="orange")

#legend(1, g_range[4], c("ctime","dtime", "ttime", "wait"), cex=0.8, col=c("blue","red", "green", "orange"), pch=21:22, lty=1:2);
#legend(1, g_range[4], c("ctime","dtime", "ttime", "wait"), col=c("blue","red", "green", "orange"));
legend( 800, 0.5, c("ctime","dtime", "ttime", "wait"), col=c("blue","red", "green", "orange"), pch=21:22, lty=1:2);

dev.off()


