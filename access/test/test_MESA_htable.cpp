
#include "mgw_utils.h"


#define	TEST_STATUS_NUM	4
#define TEST_FIELD_NUM	9
#define TEST_LINE_NUM	7
#define TEST_COLUMN_NUM	8
#define	TEST_RUNTIME_REG_NUM	32
#define	TEST_RUNTIME_REG_LINE_NUM 6
int main(int argc,char* argv[])
{
	screen_stat_handle_t handle=NULL;
	const char* stat_path="./fs2_mgw.status";
	const char* app_name="fs2_test";
	char buff[128];
	int value=0,i=0,j=0;
	handle=FS_create_handle();

    const char* FP_HISTOGRAM_BINS="0.5,0.8,0.9,0.95";
    FS_set_para(handle, HISTOGRAM_GLOBAL_BINS, FP_HISTOGRAM_BINS, strlen(FP_HISTOGRAM_BINS)+1);

	FS_set_para(handle, APP_NAME, app_name, strlen(app_name)+1);
	value=0;
	FS_set_para(handle, FLUSH_BY_DATE, &value, sizeof(value));
	FS_set_para(handle, OUTPUT_DEVICE, stat_path, strlen(stat_path)+1);
	value=1;
	FS_set_para(handle, PRINT_MODE, &value, sizeof(value));
	value=1;
	FS_set_para(handle, CREATE_THREAD, &value, sizeof(value));
	value=2;
	FS_set_para(handle, STAT_CYCLE, &value, sizeof(value));
	value=4096;
	FS_set_para(handle, MAX_STAT_FIELD_NUM, &value, sizeof(value));


	//int status_ids[TEST_STATUS_NUM], field_ids[TEST_FIELD_NUM], line_ids[TEST_LINE_NUM+TEST_RUNTIME_REG_LINE_NUM], column_ids[TEST_COLUMN_NUM];
	//int runtime_status_ids[TEST_RUNTIME_REG_NUM];
    int line_ids[2], column_ids[4];
    /*
	for(i=0;i<TEST_STATUS_NUM;i++)
	{
		snprintf(buff,sizeof(buff),"status_%02d",i);
		status_ids[i]=FS_register(handle, FS_STYLE_STATUS, FS_CALC_CURRENT,buff);
	}
	for(i=0;i<TEST_FIELD_NUM;i++)
	{
		snprintf(buff,sizeof(buff),"field_%02d",i);
		field_ids[i]=FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT,buff);
	}
	for(i=0;i<TEST_LINE_NUM;i++)
	{
		snprintf(buff,sizeof(buff),"line_%d",i);
		line_ids[i]=FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT,buff);
	}
    */
    snprintf(buff,sizeof(buff),"read_from_tun");
    column_ids[0] = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,buff);
    
    snprintf(buff,sizeof(buff),"write_to_tun");
    column_ids[1] = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,buff);
    
    snprintf(buff,sizeof(buff),"recv_from_mrl");
    column_ids[2] = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,buff);

    snprintf(buff,sizeof(buff),"send_to_mrl");
    column_ids[3] = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT,buff);

    snprintf(buff,sizeof(buff),"packet");
	line_ids[0]=FS_register(handle, FS_STYLE_LINE, FS_CALC_SPEED,buff); 

    snprintf(buff,sizeof(buff),"byte");
	line_ids[1]=FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT,buff); 

    snprintf(buff,sizeof(buff), "snat_latency");
    int snat_latency=FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

    snprintf(buff,sizeof(buff), "dnat_latency");
    int dnat_latency=FS_register_histogram(handle, FS_CALC_SPEED, buff, 1, 30*1000, 3);

	//value=column_ids[2];
	//FS_set_para(handle, ID_INVISBLE, &value, sizeof(value));
	snprintf(buff,sizeof(buff),"c4/c1");
	FS_register_ratio(handle,
				column_ids[3],
				column_ids[0],
				1,
				FS_STYLE_COLUMN,
				FS_CALC_CURRENT,
				buff);

    snprintf(buff,sizeof(buff),"c2/c3");     
    FS_register_ratio(handle,
				column_ids[1],
				column_ids[2],
				1,
				FS_STYLE_COLUMN,
				FS_CALC_CURRENT,
				buff);

	FS_start(handle);
    i = 0;
	while (1)
	{
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        for(j=0;j<4;j++)
        {
            FS_operate(handle, line_ids[0], column_ids[j], FS_OP_ADD, 10);
        }
        for(j=0;j<4;j++)
        {
            FS_operate(handle, line_ids[1], column_ids[j], FS_OP_ADD, 800);
        }
		sleep(1);
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        long long cost_time = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
        cost_time = 10;
        FS_operate(handle, snat_latency, 0, FS_OP_SET, cost_time * i);
        FS_operate(handle, dnat_latency, 0, FS_OP_SET, cost_time * i);
        i++;
	}
}