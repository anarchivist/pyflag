all: pdf_tests

pdf_tests: test?.dd
	for f in test?.dd; do \
## Create an index of PDF objects \
		python pdf_carver.py -c -i $$f.idx $$f && \
## Coalesce maps \
		python pdf_carver.py -m -i $$f.idx $$f && \
## Brute force the discontinueties \
		python PDFForcer.py -m *-*.map -o $$f.pdf $$f && \
## Check that its ok: \
		cmp $$f.pdf sample.pdf && \
		rm *.map $$f.idx ;\
	done

test?.dd: test_maps/map?.map
	for i in `seq 1 3`; do python Tester.py \
	 -m test_maps/map$${i}.map -w test$${i}.dd sample.pdf; done

clean:
	rm -f test?.dd* *.map