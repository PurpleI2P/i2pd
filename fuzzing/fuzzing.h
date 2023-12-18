#ifndef	_FUZZING_H_
#define	_FUZZING_H_

#include <stdint.h>
#include <stddef.h>


void	fuzzing_tick(void);

void	fuzzing_throttle(void);

bool	fuzzing_testinput(const uint8_t * data, size_t size);


#endif	/* !_FUZZING_H_ */
