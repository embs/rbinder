#!/usr/bin/env Rscript

library(ggplot2)

scenarios <- sub('.log', '', list.files('./log'))
means = c()
errs = c()
plotsdir <- './plots/'
dir.create(plotsdir, showWarnings=FALSE)

for(scenario in scenarios) {
  filename <- paste('./log/', scenario, '.log', sep='')
  data <- read.csv(file=filename, head=FALSE)
  error <- qt(0.975, df=length(data$V1)-1)*sd(data$V1)/sqrt(length(data$V1))

  means[scenario] = mean(data$V1)
  errs[scenario] = error

  # Boxplot.
  png(filename=paste(plotsdir, scenario, '-boxplot.png', sep=''))
  boxplot(data$V1)
  dev.off()
}

# Bar plot with error bars.
plotdata <- data.frame(scenarios, means, errs)
colnames(plotdata) <- c('scenario', 'mean', 'err')
plot <- ggplot(data=plotdata, aes(x=scenario, y=mean)) +
                geom_bar(stat="identity") +
                geom_errorbar(aes(ymin=mean-err, ymax=mean+err),
                              width=.2,
                              position=position_dodge(.9))
png(filename=paste(plotsdir, 'means.png', sep=''))
print(plot)
dev.off()
